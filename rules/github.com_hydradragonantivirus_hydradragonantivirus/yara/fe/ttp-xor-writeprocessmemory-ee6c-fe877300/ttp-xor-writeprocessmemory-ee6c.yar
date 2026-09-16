rule TTP_XOR_WriteProcessMemory_ee6c {
  strings:
    $key_ee6c = { b9 1e [2] 8b 3c [2] 8d 09 [2] a3 09 [2] 9c 15 }

  condition:
    any of them
}