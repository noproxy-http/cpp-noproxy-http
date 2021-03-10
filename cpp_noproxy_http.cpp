/*
 * Copyright 2021, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "json.hpp"

namespace { // anonymous

// declaration from bch_functions.h
typedef int (*bch_send_response_type)(
        void* request,
        int http_status,
        const char* headers, int headers_len,
        char* data, int data_len);

struct metadata {
    std::string uri;
    std::string args;
    std::string unparsed_uri;
    std::string method;
    std::string protocol;
    std::string data_temp_file;
    std::map<std::string, std::string> headers;

    metadata() { }

    metadata(const char* mdata, int mdata_len) {
        const char* end = mdata + static_cast<size_t> (mdata_len);
        nlohmann::json obj = nlohmann::json::parse(mdata, end);
        obj.at("uri").get_to(this->uri);
        obj.at("args").get_to(this->args);
        obj.at("unparsedUri").get_to(this->unparsed_uri);
        obj.at("method").get_to(this->method);
        obj.at("protocol").get_to(this->protocol);
        if (obj["dataTempFile"].is_string()) {
            obj.at("dataTempFile").get_to(this->data_temp_file);
        }
        this->headers = std::map<std::string, std::string>();
        for (auto& ha : obj["headers"].items()) {
            std::string key = ha.key();
            std::string value = ha.value();
            this->headers.insert(std::make_pair(std::move(key), std::move(value)));
        }
    }
};

struct request {
    void* handle;
    metadata meta;
    const char* data;
    size_t data_len;

    request() { }

    request(void* handle_in, const char* metadata_in, int metadata_len_in, 
            const char* data_in, int data_len_in) :
    handle(handle_in),
    meta(metadata_in, metadata_len_in),
    data(data_in),
    data_len(static_cast<size_t>(data_len_in)) { }
};

// globals

// callback to use for sending response
bch_send_response_type send_response = nullptr;

// background thread where response is prepared
std::thread th;

// requests queue, mutex and a condition var for it
std::queue<request> queue;
std::mutex mtx;
std::condition_variable cv;

void receive_request() {
    request req;
    { // receive request
        std::unique_lock<std::mutex> lock{mtx};
        if (queue.empty()) {
            cv.wait(lock, [] {
                return !queue.empty();
            });
        }
        req = std::move(queue.front());
        queue.pop();
    }

    // prepare response
    std::string msg = "Hello from C++, your request was received on path: [" + req.meta.uri + "]\n";
    char* resp_data = static_cast<char*>(std::malloc(msg.length()));
    std::memcpy(resp_data, msg.data(), msg.length());
    nlohmann::json headers_json;
    headers_json["X--Custom-CPP-Header"] = "foo";
    std::string headers = headers_json.dump();

    // send response
    send_response(req.handle, 200,
            headers.data(), static_cast<int>(headers.length()),
            resp_data, static_cast<int>(msg.length()));
}

} // namespace

extern "C" 
#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
int bch_initialize(bch_send_response_type response_callback,
        const char* hanler_config, int hanler_config_len) {

    send_response = response_callback;

    th = std::thread([]{
        for(;;) {
            receive_request();
        }
    });
    th.detach();

    auto str = std::string(hanler_config, static_cast<size_t>(hanler_config_len));
    std::cerr << "CPP handler init called, config: [" << str << "]" << std::endl;

    return 0;
}

extern "C"
#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
int bch_receive_request(void* handle,
        const char* metadata, int metadata_len,
        const char* data, int data_len) {

    std::cerr << "CPP handler received a request" << std::endl;
    request req = request(handle, metadata, metadata_len, data, data_len);

    std::lock_guard<std::mutex> guard{mtx};
    queue.push(std::move(req));
    cv.notify_all();

    return 0;
}

extern "C"
#ifdef _WIN32
__declspec( dllexport )
#endif // _WIN32
void bch_free_response_data(void* data) {
    std::free(data);
}