rule TTP_XOR_WriteProcessMemory_fdce {
  strings:
    $key_fdce = { aa bc [2] 98 9e [2] 9e ab [2] b0 ab [2] 8f b7 }

  condition:
    any of them
}