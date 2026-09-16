rule TTP_XOR_WriteProcessMemory_c27e {
  strings:
    $key_c27e = { 95 0c [2] a7 2e [2] a1 1b [2] 8f 1b [2] b0 07 }

  condition:
    any of them
}