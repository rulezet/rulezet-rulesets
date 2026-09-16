rule TTP_XOR_WriteProcessMemory_5f93 {
  strings:
    $key_5f93 = { 08 e1 [2] 3a c3 [2] 3c f6 [2] 12 f6 [2] 2d ea }

  condition:
    any of them
}