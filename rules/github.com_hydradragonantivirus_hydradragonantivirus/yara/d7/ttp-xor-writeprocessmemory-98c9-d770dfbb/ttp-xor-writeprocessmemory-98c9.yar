rule TTP_XOR_WriteProcessMemory_98c9 {
  strings:
    $key_98c9 = { cf bb [2] fd 99 [2] fb ac [2] d5 ac [2] ea b0 }

  condition:
    any of them
}