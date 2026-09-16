rule TTP_XOR_QUAD_CurrentVersionRun_416c {
  strings:
    $key_416c = { 12 03 [2] 36 0d [2] 1d 21 [2] 33 03 [2] 27 18 [2] 28 02 [2] 36 1f [2] 34 1e [2] 2f 18 [2] 33 1f [2] 2f 30 }

  condition:
    any of them
}