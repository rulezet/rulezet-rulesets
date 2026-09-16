rule TTP_XOR_WriteProcessMemory_eac9 {
  strings:
    $key_eac9 = { bd bb [2] 8f 99 [2] 89 ac [2] a7 ac [2] 98 b0 }

  condition:
    any of them
}