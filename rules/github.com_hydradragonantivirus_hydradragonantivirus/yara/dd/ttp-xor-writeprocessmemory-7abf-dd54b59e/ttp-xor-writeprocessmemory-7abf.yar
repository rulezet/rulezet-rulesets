rule TTP_XOR_WriteProcessMemory_7abf {
  strings:
    $key_7abf = { 2d cd [2] 1f ef [2] 19 da [2] 37 da [2] 08 c6 }

  condition:
    any of them
}