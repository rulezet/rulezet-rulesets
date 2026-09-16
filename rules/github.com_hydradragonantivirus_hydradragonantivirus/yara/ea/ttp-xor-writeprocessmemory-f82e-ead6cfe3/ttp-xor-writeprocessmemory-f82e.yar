rule TTP_XOR_WriteProcessMemory_f82e {
  strings:
    $key_f82e = { af 5c [2] 9d 7e [2] 9b 4b [2] b5 4b [2] 8a 57 }

  condition:
    any of them
}