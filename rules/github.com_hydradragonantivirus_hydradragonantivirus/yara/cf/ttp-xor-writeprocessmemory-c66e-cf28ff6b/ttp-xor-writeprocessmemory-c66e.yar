rule TTP_XOR_WriteProcessMemory_c66e {
  strings:
    $key_c66e = { 91 1c [2] a3 3e [2] a5 0b [2] 8b 0b [2] b4 17 }

  condition:
    any of them
}