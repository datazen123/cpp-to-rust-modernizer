# Real Juliet Test Suite Benchmark Report (cpp-to-rust-modernizer)

Source: https://raw.githubusercontent.com/arichardson/juliet-test-suite-c/master/testcases/CWE121_Stack_Based_Buffer_Overflow/s02/CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c
(NIST's own official Juliet Test Suite for C/C++ v1.3, fetched live via a public GitHub mirror of the NIST SARD release - not vendored, not paraphrased.)

NIST's own file header labels this **CWE-121: Stack Based Buffer Overflow** ("BadSource: Point data to a buffer that does not have space for a NULL terminator... BadSink: Copy string to data using strcpy()").

**Result: Claude CORRECTLY identify CWE-121** in its analysis of this file.

CWEs Claude's analysis cited: ['CWE-121', 'CWE-676']

## Full analysis Claude produced

```json
{
  "summary": "This is a test case file demonstrating a stack-based buffer overflow vulnerability. It contains two functions: a 'bad' function that intentionally creates a buffer overflow by copying a 10-character string plus null terminator into a 10-byte buffer that lacks space for the null terminator, and a 'good' function that fixes this by using an 11-byte buffer with proper space for the null terminator.",
  "memory_safety_risks": [
    {
      "location": "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01_bad() function, lines 32-38",
      "cwe": "CWE-121",
      "description": "Stack-based buffer overflow (off-by-one error). The dataBadBuffer is declared with size 10 bytes (line 32), but strcpy() at line 38 attempts to copy an 11-byte string (10 characters from SRC_STRING plus null terminator) into this buffer. This writes one byte past the end of dataBadBuffer, corrupting adjacent stack memory. This is a classic off-by-one error where the buffer size calculation fails to account for the null terminator."
    },
    {
      "location": "CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01_bad() function, line 38",
      "cwe": "CWE-676",
      "description": "Use of potentially dangerous function strcpy(). The strcpy() function does not perform bounds checking and will write beyond the destination buffer if the source is larger. Even though this particular case demonstrates an intentional overflow, strcpy() should generally be replaced with safer alternatives like strncpy() or strlcpy() in production code."
    },
    {
      "location": "goodG2B() function, line 57",
      "cwe": "CWE-676",
      "description": "Use of potentially dangerous function strcpy(). Although this 'good' example correctly sizes the buffer to prevent overflow in this specific case, strcpy() remains inherently unsafe because it provides no protection against future code changes or different input scenarios. A length-checked copy function would be more robust."
    }
  ]
}
```

This is a pass/fail check on one real, NIST-labeled case, not a statistical benchmark - reported plainly rather than manufacturing a precision/recall number from a sample size of one.
