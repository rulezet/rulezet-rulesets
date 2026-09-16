rule TTP_XOR_WriteProcessMemory_face {
  strings:
    $key_face = { ad bc [2] 9f 9e [2] 99 ab [2] b7 ab [2] 88 b7 }

  condition:
    any of them
}