rule md5_4adef02197f50b9cc6918aa06132b2f6 {
    
    strings: $ = /\{\s*eval\s*\(\s*\$.{1,5}\s*\(\$\{\s*\$.{1,5}\s*\}\[\s*'.{1,10}'\s*\]\s*\)\s*\);\}/
    condition: any of them
}