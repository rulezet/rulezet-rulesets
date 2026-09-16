rule TTP_XOR_WriteProcessMemory_c35c {
  strings:
    $key_c35c = { 94 2e [2] a6 0c [2] a0 39 [2] 8e 39 [2] b1 25 }

  condition:
    any of them
}