rule TTP_XOR_WriteProcessMemory_cafb {
  strings:
    $key_cafb = { 9d 89 [2] af ab [2] a9 9e [2] 87 9e [2] b8 82 }

  condition:
    any of them
}