#!/bin/bash
# Daily automated system backup
tar -czf /var/backups/system_$(date +%Y%m%d).tar.gz /etc /var/www 2>/dev/null
