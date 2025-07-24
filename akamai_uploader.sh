#!/bin/bash

INPUT_FILE="akamai_blocklist.txt"
OUTPUT_FILE="akamai_edge_ipset.json"

echo "[+] Generating Akamai edge IP set..."

cat <<EOF > $OUTPUT_FILE
{
  "type": "IPList",
  "name": "KraawnShieldAutoBlock",
  "list": [
EOF

# Add IPs
count=0
while IFS= read -r ip; do
  if [[ $count -gt 0 ]]; then echo "," >> $OUTPUT_FILE; fi
  echo "    \"$ip\"" >> $OUTPUT_FILE
  ((count++))
done < "$INPUT_FILE"

echo "  ]" >> $OUTPUT_FILE
echo "}" >> $OUTPUT_FILE

echo "[+] Saved Akamai IP list → $OUTPUT_FILE"
