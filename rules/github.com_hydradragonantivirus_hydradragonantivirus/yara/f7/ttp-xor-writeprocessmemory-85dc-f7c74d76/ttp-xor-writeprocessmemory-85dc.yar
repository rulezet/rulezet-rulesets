rule TTP_XOR_WriteProcessMemory_85dc {
  strings:
    $key_85dc = { d2 ae [2] e0 8c [2] e6 b9 [2] c8 b9 [2] f7 a5 }

  condition:
    any of them
}