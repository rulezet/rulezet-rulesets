rule TTP_XOR_WriteProcessMemory_58c9 {
  strings:
    $key_58c9 = { 0f bb [2] 3d 99 [2] 3b ac [2] 15 ac [2] 2a b0 }

  condition:
    any of them
}