rule TTP_XOR_QUAD_CurrentVersionRun_416b {
  strings:
    $key_416b = { 12 04 [2] 36 0a [2] 1d 26 [2] 33 04 [2] 27 1f [2] 28 05 [2] 36 18 [2] 34 19 [2] 2f 1f [2] 33 18 [2] 2f 37 }

  condition:
    any of them
}