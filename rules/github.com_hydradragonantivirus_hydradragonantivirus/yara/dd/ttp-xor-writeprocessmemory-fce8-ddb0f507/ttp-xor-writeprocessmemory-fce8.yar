rule TTP_XOR_WriteProcessMemory_fce8 {
  strings:
    $key_fce8 = { ab 9a [2] 99 b8 [2] 9f 8d [2] b1 8d [2] 8e 91 }

  condition:
    any of them
}