rule TTP_XOR_WriteProcessMemory_fafe {
  strings:
    $key_fafe = { ad 8c [2] 9f ae [2] 99 9b [2] b7 9b [2] 88 87 }

  condition:
    any of them
}