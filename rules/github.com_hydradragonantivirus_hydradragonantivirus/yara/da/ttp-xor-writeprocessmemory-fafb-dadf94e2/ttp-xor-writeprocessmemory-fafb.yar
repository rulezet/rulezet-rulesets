rule TTP_XOR_WriteProcessMemory_fafb {
  strings:
    $key_fafb = { ad 89 [2] 9f ab [2] 99 9e [2] b7 9e [2] 88 82 }

  condition:
    any of them
}