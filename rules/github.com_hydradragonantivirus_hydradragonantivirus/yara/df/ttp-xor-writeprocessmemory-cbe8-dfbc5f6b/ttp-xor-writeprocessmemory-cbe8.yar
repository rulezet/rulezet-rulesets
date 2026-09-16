rule TTP_XOR_WriteProcessMemory_cbe8 {
  strings:
    $key_cbe8 = { 9c 9a [2] ae b8 [2] a8 8d [2] 86 8d [2] b9 91 }

  condition:
    any of them
}