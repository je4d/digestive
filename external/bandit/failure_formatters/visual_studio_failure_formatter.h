#ifndef BANDIT_VISUAL_STUDIO_FAILURE_FORMATTER_H
#define BANDIT_VISUAL_STUDIO_FAILURE_FORMATTER_H

namespace bandit {

  struct visual_studio_failure_formatter : public failure_formatter
  {
    std::string format(const assertion_exception& err) const
    {
      std::stringstream ss;
      if(err.file_name().size())
      {
        ss << err.file_name();

        if(err.line_number())
        {
          ss << "(" << err.line_number() << ")";
        }

        ss << ": ";
      }
      else
      {
        ss << "bandit: ";
      }

      ss << err.what();

      return ss.str();

    }
  };

}

#endif
