def nuix_worker_item_callback(worker_item)

	rules = {
		"or[0-9A-F%\\s\\(\\/*]+\\d=\\d" => 25,
		"like[\\s%0-9A-F\\/*]+['\"]%" => 50,
		"or[0-9%A-F\\s\\/*]+['\"].['\"]=['\"]" => 25,
		"sleep[\\s%0-9A-F\\/*]+\\d" => 50,
		"waitfor[%0-9A-F\\s\\/*]+delay" => 75,
		"select[\\s%A-F0-9\\/*]+" => 50,
		"union.*?select" => 75,
		"exec[\\s%A-F0-9\\/*]+(xp|sp|master)" => 75,
		"--" => 10,
	}


  source_item = worker_item.source_item
	begin
		if(source_item.type.name =~ /text\/x-common-log-entry/ or source_item.type.name =~ /application\/vnd.ms-iis-log-entry/)
			score = 0
			data =  source_item.properties.to_s
			rules.keys.each do |k|
				score += rules[k] if data =~ /#{k}/i
			end
			worker_item.add_custom_metadata("SQLi Score", score, "integer", "user")
			if score >= 100
				worker_item.add_tag("CTAT Intel/SQLi Detected")
			end
		end
	rescue
		return
	end
end
