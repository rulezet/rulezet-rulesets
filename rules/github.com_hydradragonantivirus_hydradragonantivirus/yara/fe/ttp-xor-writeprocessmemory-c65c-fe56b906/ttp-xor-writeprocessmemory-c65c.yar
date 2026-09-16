rule TTP_XOR_WriteProcessMemory_c65c {
  strings:
    $key_c65c = { 91 2e [2] a3 0c [2] a5 39 [2] 8b 39 [2] b4 25 }

  condition:
    any of them
}