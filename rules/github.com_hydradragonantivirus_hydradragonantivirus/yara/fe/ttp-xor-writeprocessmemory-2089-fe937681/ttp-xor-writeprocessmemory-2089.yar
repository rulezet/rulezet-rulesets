rule TTP_XOR_WriteProcessMemory_2089 {
  strings:
    $key_2089 = { 77 fb [2] 45 d9 [2] 43 ec [2] 6d ec [2] 52 f0 }

  condition:
    any of them
}