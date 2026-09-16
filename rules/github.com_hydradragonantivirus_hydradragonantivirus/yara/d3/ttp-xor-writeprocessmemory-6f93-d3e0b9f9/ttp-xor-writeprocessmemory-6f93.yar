rule TTP_XOR_WriteProcessMemory_6f93 {
  strings:
    $key_6f93 = { 38 e1 [2] 0a c3 [2] 0c f6 [2] 22 f6 [2] 1d ea }

  condition:
    any of them
}