rule TTP_XOR_WriteProcessMemory_f80b {
  strings:
    $key_f80b = { af 79 [2] 9d 5b [2] 9b 6e [2] b5 6e [2] 8a 72 }

  condition:
    any of them
}