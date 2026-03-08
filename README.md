larptool dht crawler
steals IPs from P2P 
--max-nodes | Stop after N nodes
--max-depth | BFS depth limit
--concurrency | Parallel queries
--timeout | Per-query timeout
--ping-validate | Filter dead nodes
--get-peers | Find torrent peers
-o /--output | Output file (default:dht_crawl_results.json)
-v | Debug logging

Common Examples
Discover more nodes with verbose logging:
bashpython dht_crawler.py --max-nodes 500 --max-depth 10 -v

Ping-validate discovered nodes (filters out dead nodes after crawling):
bashpython dht_crawler.py --max-nodes 200 --ping-validate

Run the full pipeline — crawl, validate, then find peers for test torrents:
bashpython dht_crawler.py --max-nodes 300 --ping-validate --get-peers -v

Save results to a custom file:
bashpython dht_crawler.py --output my_results.json

Tune concurrency and timeouts (useful on slow/fast connections):
bashpython dht_crawler.py --concurrency 50 --timeout 6.0 --delay 0.05

