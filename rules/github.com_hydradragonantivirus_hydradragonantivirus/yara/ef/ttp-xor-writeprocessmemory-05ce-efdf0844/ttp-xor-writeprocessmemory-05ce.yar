rule TTP_XOR_WriteProcessMemory_05ce {
  strings:
    $key_05ce = { 52 bc [2] 60 9e [2] 66 ab [2] 48 ab [2] 77 b7 }

  condition:
    any of them
}