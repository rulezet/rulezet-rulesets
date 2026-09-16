rule TTP_XOR_WriteProcessMemory_70ee {
  strings:
    $key_70ee = { 27 9c [2] 15 be [2] 13 8b [2] 3d 8b [2] 02 97 }

  condition:
    any of them
}