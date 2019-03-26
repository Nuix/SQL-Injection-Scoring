# Scores properties based on rules.
# Adds custom metadata "SQLi Score"
# Adds tag "CTAT Intel|SQLi Detected" if score >= 100
def nuix_worker_item_callback(worker_item)
  rules = {
    'or[0-9A-F%\\s\\(\\/*]+\\d=\\d' => 25,
    "like[\\s%0-9A-F\\/*]+['\"]%" => 50,
    "or[0-9%A-F\\s\\/*]+['\"].['\"]=['\"]" => 25,
    'sleep[\\s%0-9A-F\\/*]+\\d' => 50,
    'waitfor[%0-9A-F\\s\\/*]+delay' => 75,
    'select[\\s%A-F0-9\\/*]+' => 50,
    'union.*?select' => 75,
    'exec[\\s%A-F0-9\\/*]+(xp|sp|master)' => 75,
    '--' => 10
  }

  source_item = worker_item.source_item
  type = source_item.get_type.get_name
  begin
    if type =~ %r{text/x-common-log-entry} || type =~ %r{application/vnd.ms-iis-log-entry}
      data = source_item.get_properties.to_s
      score = 0
      rules.each { |k, v| score += v if data =~ /#{k}/i }
      worker_item.add_custom_metadata('SQLi Score', score, 'integer', 'user')
      worker_item.add_tag('CTAT Intel|SQLi Detected') if score >= 100
    end
  rescue StandardError
    return
  end
end
