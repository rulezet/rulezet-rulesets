rule TTP_XOR_WriteProcessMemory_3f93 {
  strings:
    $key_3f93 = { 68 e1 [2] 5a c3 [2] 5c f6 [2] 72 f6 [2] 4d ea }

  condition:
    any of them
}