rule TTP_XOR_WriteProcessMemory_f96e {
  strings:
    $key_f96e = { ae 1c [2] 9c 3e [2] 9a 0b [2] b4 0b [2] 8b 17 }

  condition:
    any of them
}