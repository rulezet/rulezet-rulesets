rule TTP_XOR_WriteProcessMemory_e339 {
  strings:
    $key_e339 = { b4 4b [2] 86 69 [2] 80 5c [2] ae 5c [2] 91 40 }

  condition:
    any of them
}