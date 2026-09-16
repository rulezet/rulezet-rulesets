rule TTP_XOR_WriteProcessMemory_c694 {
  strings:
    $key_c694 = { 91 e6 [2] a3 c4 [2] a5 f1 [2] 8b f1 [2] b4 ed }

  condition:
    any of them
}