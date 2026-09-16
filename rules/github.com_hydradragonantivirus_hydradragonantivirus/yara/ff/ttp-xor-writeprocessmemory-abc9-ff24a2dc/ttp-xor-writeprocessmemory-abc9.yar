rule TTP_XOR_WriteProcessMemory_abc9 {
  strings:
    $key_abc9 = { fc bb [2] ce 99 [2] c8 ac [2] e6 ac [2] d9 b0 }

  condition:
    any of them
}