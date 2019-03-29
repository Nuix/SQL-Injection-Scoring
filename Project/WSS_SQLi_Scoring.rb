# Scores properties based on rules.
# Adds custom metadata "SQLi Score"
# Adds tag "CTAT Intel|SQLi Detected" if score >= 100
# @version 1.1.0

TYPES = [%r{text/x-common-log-entry}, %r{application/vnd.ms-iis-log-entry}].freeze
RULES = {
  %r{or[0-9A-F%\s\(/*]+\d=\d}i => 25,
  %r{like[\s%0-9A-F/*]+['"]%}i => 50,
  %r{or[0-9%A-F\s/*]+['"].['"]=['"]}i => 25,
  %r{sleep[\s%0-9A-F/*]+\d}i => 50,
  %r{waitfor[%0-9A-F\s/*]+delay}i => 75,
  %r{select[\s%A-F0-9/*]+}i => 50,
  /union.*?select/i => 75,
  %r{exec[\s%A-F0-9/*]+(xp|sp|master)}i => 75,
  /--/i => 10
}.freeze

def nuix_worker_item_callback(worker_item)
  source_item = worker_item.source_item
  type = source_item.get_type.get_name
  return nil unless TYPES.any? { |t| type =~ t }

  begin
    score = score_text(source_item.get_properties.to_s)
    worker_item.add_custom_metadata('SQLi Score', score, 'integer', 'user')
    worker_item.add_tag('CTAT Intel|SQLi Detected') if score >= 100
  rescue StandardError
    return
  end
end

def score_text(text)
  score = 0
  RULES.each { |k, v| score += v if text =~ k }
  score
end
