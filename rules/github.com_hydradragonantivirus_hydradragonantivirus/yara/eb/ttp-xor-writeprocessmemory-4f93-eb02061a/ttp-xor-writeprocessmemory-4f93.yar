rule TTP_XOR_WriteProcessMemory_4f93 {
  strings:
    $key_4f93 = { 18 e1 [2] 2a c3 [2] 2c f6 [2] 02 f6 [2] 3d ea }

  condition:
    any of them
}