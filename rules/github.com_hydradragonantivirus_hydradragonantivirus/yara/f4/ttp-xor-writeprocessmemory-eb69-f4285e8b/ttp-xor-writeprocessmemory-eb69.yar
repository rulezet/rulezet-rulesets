rule TTP_XOR_WriteProcessMemory_eb69 {
  strings:
    $key_eb69 = { bc 1b [2] 8e 39 [2] 88 0c [2] a6 0c [2] 99 10 }

  condition:
    any of them
}