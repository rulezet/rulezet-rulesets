rule TTP_XOR_WriteProcessMemory_fcfb {
  strings:
    $key_fcfb = { ab 89 [2] 99 ab [2] 9f 9e [2] b1 9e [2] 8e 82 }

  condition:
    any of them
}