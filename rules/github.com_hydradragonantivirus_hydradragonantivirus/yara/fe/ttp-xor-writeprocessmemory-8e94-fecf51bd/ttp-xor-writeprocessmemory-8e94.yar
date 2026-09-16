rule TTP_XOR_WriteProcessMemory_8e94 {
  strings:
    $key_8e94 = { d9 e6 [2] eb c4 [2] ed f1 [2] c3 f1 [2] fc ed }

  condition:
    any of them
}