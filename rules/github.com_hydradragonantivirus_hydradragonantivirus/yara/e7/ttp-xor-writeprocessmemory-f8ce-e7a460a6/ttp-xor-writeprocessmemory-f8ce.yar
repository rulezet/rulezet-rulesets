rule TTP_XOR_WriteProcessMemory_f8ce {
  strings:
    $key_f8ce = { af bc [2] 9d 9e [2] 9b ab [2] b5 ab [2] 8a b7 }

  condition:
    any of them
}