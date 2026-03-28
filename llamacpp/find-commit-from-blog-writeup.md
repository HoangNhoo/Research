# Phương pháp tìm commit hash từ blog writeup

## Bối cảnh

Khi đọc một blog writeup về security vulnerability (ví dụ: exploit RCE), tác giả thường reference code với format `file:line_number`. Ta có thể sử dụng thông tin này để xác định chính xác commit mà tác giả đã sử dụng.

**Case study:** Tìm commit hash của llama.cpp từ blog https://retr0.blog/blog/llama-rpc-rce

---

## Phương pháp: Line Matching

### Bước 1: Trích xuất số dòng từ blog

Blog thường reference code với format `file:line_number`. Grep các pattern này:

```bash
# Tải nội dung blog (hoặc copy vào file)
curl -s "https://retr0.blog/blog/llama-rpc-rce" > blog_content.txt

# Grep các pattern file:line
grep -oE "ggml-rpc\.cpp:[0-9]+" blog_content.txt | sort -u
grep -oE "ggml-backend\.cpp:[0-9]+" blog_content.txt | sort -u
grep -oE "ggml-backend-impl\.h:[0-9]+" blog_content.txt | sort -u
```

**Kết quả từ blog Retr0:**

| File | Line numbers |
|------|--------------|
| `ggml-rpc.cpp` | 804, 805, 843, 848, 854, 924 |
| `ggml-backend.cpp` | 1911 |
| `ggml-backend-impl.h` | 60 |

### Bước 2: Xác định code context từ blog

Ghi nhận đoạn code được trích dẫn tại các dòng đó:

```cpp
// ggml/src/ggml-rpc/ggml-rpc.cpp:843
result->buffer = reinterpret_cast<ggml_backend_buffer_t>(tensor->buffer);

// ggml/src/ggml-rpc/ggml-rpc.cpp:848
if (result->buffer) {
    // require that the tensor data does not go beyond the buffer end
    uint64_t tensor_size = (uint64_t) ggml_nbytes(result);
    uint64_t buffer_start = (uint64_t) ggml_backend_buffer_get_base(result->buffer);
    uint64_t buffer_size = (uint64_t) ggml_backend_buffer_get_size(result->buffer);
    GGML_ASSERT(tensor->data + tensor_size >= tensor->data); // check for overflow
    GGML_ASSERT(tensor->data >= buffer_start && tensor->data + tensor_size <= buffer_start + buffer_size);
}

// ggml/src/ggml-rpc/ggml-rpc.cpp:924
{
    const size_t p0 = (size_t) ggml_backend_buffer_get_base(tensor->buffer);
    const size_t p1 = p0 + ggml_backend_buffer_get_size(tensor->buffer);

    if (request.tensor.data + request.offset < p0 ||
        request.tensor.data + request.offset >= p1 ||
        request.size > (p1 - request.tensor.data - request.offset)) {
            GGML_ABORT("[%s] tensor->data out of bounds\n", __func__);
    }
}

// ggml/src/ggml-backend-impl.h:60
struct ggml_backend_buffer {
    struct ggml_backend_buffer_i  iface;
    ggml_backend_buffer_type_t    buft;
    void * context;
    size_t size;
    enum ggml_backend_buffer_usage usage;
};
```

### Bước 3: Tìm commit candidates

Liệt kê các commits liên quan đến file được đề cập:

```bash
cd /path/to/llama.cpp

# Liệt kê commits thay đổi file ggml-rpc.cpp
git log --oneline --all -- ggml/src/ggml-rpc/ggml-rpc.cpp | head -50
```

### Bước 4: Line matching - tìm commit khớp số dòng

Với mỗi commit candidate, kiểm tra xem số dòng có khớp không:

```bash
# Tìm dòng chứa "if (result->buffer)" trong commit cụ thể
git show <commit>:ggml/src/ggml-rpc/ggml-rpc.cpp | grep -n "if (result->buffer)"

# Xem context của các dòng cụ thể (ví dụ: 843-860)
git show <commit>:ggml/src/ggml-rpc/ggml-rpc.cpp | sed -n '843,860p'
```

**Kết quả so sánh cho case study:**

| Commit | `if (result->buffer)` ở dòng | Match với blog (848)? |
|--------|------------------------------|----------------------|
| `2fb3c32a1` | 907 | ❌ |
| `c0d4843225e` | 907 | ❌ |
| `6da5bec81` | không khớp | ❌ |
| `ae8de6d50` | **848** | ✅ |
| `5931c1f23` | **848** | ✅ |

### Bước 5: Verify đầy đủ các dòng

Với commit candidate, verify TẤT CẢ các dòng từ blog:

```bash
COMMIT="ae8de6d50"

# Line 843-860 (deserialize_tensor check)
git show $COMMIT:ggml/src/ggml-rpc/ggml-rpc.cpp | sed -n '843,860p'

# Line 920-940 (p0/p1 boundary check)
git show $COMMIT:ggml/src/ggml-rpc/ggml-rpc.cpp | sed -n '920,940p'

# Line 804-810 (buffer_get_base)
git show $COMMIT:ggml/src/ggml-rpc/ggml-rpc.cpp | sed -n '800,810p'

# ggml-backend-impl.h line 60 (struct definition)
git show $COMMIT:ggml/src/ggml-backend-impl.h | sed -n '55,70p'
```

---

## Kết quả case study

### Commit gốc tác giả sử dụng để phát triển exploit:

```
ae8de6d50a09d49545e0afab2e50cc4acfb280e2
```

| Field | Value |
|-------|-------|
| Author | Diego Devesa |
| Date | Thu Nov 14 18:04:35 2024 +0100 |
| Message | `ggml : build backends as libraries (#10256)` |
| PR | #10256 |

### Commit để reproduce exploit (từ Hacker News):

```
c0d4843225eed38903ea71ef302a02fa0b27f048
```

- Đây là commit ngay trước fix, dễ dùng để test
- Số dòng đã thay đổi so với blog (848 → 907)
- Nguồn: https://news.ycombinator.com/item?id=43451935

### Commit fix vulnerability:

```
1d20e53c40c3cc848ba2b95f5bf7c075eeec8b19
```

| Field | Value |
|-------|-------|
| Author | Patrick Peng (retr0@retr0.blog) |
| Date | Thu Feb 6 09:29:13 2025 -0500 |
| Message | `rpc: fix known RCE in rpc-server (ggml/1103)` |

---

## Tóm tắt quy trình

```
┌─────────────────────────────────────────────────────────────┐
│  1. Đọc blog, grep các pattern "file:line_number"           │
│     grep -oE "filename\.cpp:[0-9]+" blog.txt               │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Ghi nhận code context tại các dòng đó từ blog          │
│     (copy đoạn code được trích dẫn)                        │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Liệt kê commits liên quan đến file                      │
│     git log --oneline -- path/to/file                      │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Với mỗi commit, kiểm tra số dòng có khớp không          │
│     git show <commit>:path/file | grep -n "pattern"        │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  5. Verify tất cả các dòng được đề cập trong blog          │
│     git show <commit>:path/file | sed -n 'X,Yp'            │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│  6. Commit nào khớp TẤT CẢ các dòng = commit gốc           │
└─────────────────────────────────────────────────────────────┘
```

---

## Script tự động hóa

```bash
#!/bin/bash
# find_commit_by_line.sh
# Usage: ./find_commit_by_line.sh <file_path> <pattern> <expected_line>

FILE_PATH=$1
PATTERN=$2
EXPECTED_LINE=$3

echo "Finding commits where '$PATTERN' is at line $EXPECTED_LINE in $FILE_PATH"
echo "=========================================="

# Get all commits that touched this file
for commit in $(git log --oneline --all -- "$FILE_PATH" | cut -d' ' -f1); do
    # Get the line number of the pattern in this commit
    line=$(git show "$commit:$FILE_PATH" 2>/dev/null | grep -n "$PATTERN" | head -1 | cut -d: -f1)
    
    if [ "$line" == "$EXPECTED_LINE" ]; then
        echo "✅ MATCH: $commit (line $line)"
        git log -1 --format="   Author: %an | Date: %ad | %s" "$commit"
    fi
done
```

**Sử dụng:**

```bash
chmod +x find_commit_by_line.sh
./find_commit_by_line.sh "ggml/src/ggml-rpc/ggml-rpc.cpp" "if (result->buffer)" 848
```

---

## Lưu ý quan trọng

1. **Số dòng thay đổi theo thời gian** - các commit sau có thể thêm/xóa code làm lệch số dòng

2. **Commit gần nhất trước fix ≠ commit gốc** - cần line matching để xác nhận chính xác

3. **Nguồn bổ sung hữu ích:**
   - Hacker News comments
   - GitHub issues/PRs liên quan
   - Exploit gist/PoC code
   - Author's Twitter/social media

4. **Timeline quan trọng:**
   - Blog date: Feb 6, 2025
   - Commit gốc: Nov 14, 2024
   - Tác giả có ~3 tháng để research trước khi publish

5. **Verify bằng nhiều dòng:** Một dòng có thể trùng ngẫu nhiên, cần verify nhiều dòng để chắc chắn

---

## References

- Blog: https://retr0.blog/blog/llama-rpc-rce
- Exploit PoC: https://gist.github.com/retr0reg/d13de3fde8f9d138fe1af48e59e630a9
- HN Discussion: https://news.ycombinator.com/item?id=43451935
- Fix PR: https://github.com/ggml-org/ggml/pull/1103
