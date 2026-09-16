rule TTP_XOR_WriteProcessMemory_7e94 {
  strings:
    $key_7e94 = { 29 e6 [2] 1b c4 [2] 1d f1 [2] 33 f1 [2] 0c ed }

  condition:
    any of them
}