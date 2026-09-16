rule TTP_XOR_WriteProcessMemory_0c39 {
  strings:
    $key_0c39 = { 5b 4b [2] 69 69 [2] 6f 5c [2] 41 5c [2] 7e 40 }

  condition:
    any of them
}