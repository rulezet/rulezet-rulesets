rule TTP_XOR_WriteProcessMemory_f87b {
  strings:
    $key_f87b = { af 09 [2] 9d 2b [2] 9b 1e [2] b5 1e [2] 8a 02 }

  condition:
    any of them
}