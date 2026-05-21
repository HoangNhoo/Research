# This repo is for reproducing POC
git clone https://github.com/ggml-org/llama.cpp.git && cd llama.cpp
git checkout dc22344088a7ee81a1e4f096459b03a72f24ccdc # Checkout a revision prior to the exploit fix in 1d20e53c40c3cc848ba2b95f5bf7c075eeec8b19
mkdir build-rpc && cd build-rpc
cmake .. -DGGML_RPC=ON
cmake --build . --config Release
cd bin/
./rpc-server -p 50052


