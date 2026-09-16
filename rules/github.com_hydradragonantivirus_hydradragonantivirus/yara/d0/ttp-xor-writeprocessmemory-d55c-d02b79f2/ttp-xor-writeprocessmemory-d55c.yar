rule TTP_XOR_WriteProcessMemory_d55c {
  strings:
    $key_d55c = { 82 2e [2] b0 0c [2] b6 39 [2] 98 39 [2] a7 25 }

  condition:
    any of them
}