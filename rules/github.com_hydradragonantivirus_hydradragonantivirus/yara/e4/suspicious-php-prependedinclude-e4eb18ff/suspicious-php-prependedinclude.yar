rule Suspicious_PHP_PrependedInclude {
  meta:
    description = "Suspicious PHP include often associated with WP-VCD."

  strings:
    $re = /^\<\?php\s+if\s*\(\s*file_exists\s*\(\s*dirname\s*\(\s*__FILE__\s*\)\s*\.\s*['"][^'"]+['"]\s*\)\s*\)\s*(include|require)(_once)?\s*\(\s*dirname\s*\(\s*__FILE__\s*\)\s*\.\s*['"][^'"]+['"]\s*\)\s*\;\s*\?\>\s*\<\?/ nocase

  condition:
    $re
}