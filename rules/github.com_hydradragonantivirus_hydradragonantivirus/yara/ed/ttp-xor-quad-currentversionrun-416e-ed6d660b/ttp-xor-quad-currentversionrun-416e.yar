rule TTP_XOR_QUAD_CurrentVersionRun_416e {
  strings:
    $key_416e = { 12 01 [2] 36 0f [2] 1d 23 [2] 33 01 [2] 27 1a [2] 28 00 [2] 36 1d [2] 34 1c [2] 2f 1a [2] 33 1d [2] 2f 32 }

  condition:
    any of them
}