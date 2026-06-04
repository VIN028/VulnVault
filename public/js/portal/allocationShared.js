(function () {
  'use strict';

  const { getWorkdaysInMonth, workingDaysBetween } = window.PortalShared || {};

  function buildAllocationMonths(summary) {
    const months = new Set();
    const today = new Date();

    summary.forEach(r => {
      [r.kickoff_date, r.start_date, r.initial_report_date, r.final_report_date].filter(Boolean).forEach(d => {
        const dt = new Date(d);
        if (!isNaN(dt.getTime())) {
          months.add(`${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}`);
        }
      });
    });

    months.add(`${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`);
    const next = new Date(today.getFullYear(), today.getMonth() + 1, 1);
    months.add(`${next.getFullYear()}-${String(next.getMonth() + 1).padStart(2, '0')}`);

    const allocationMonths = [...months].sort();
    const curVal = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`;
    const allocationMonthIdx = Math.max(0, allocationMonths.indexOf(curVal));
    return { allocationMonths, allocationMonthIdx };
  }

  function assessmentMandaysInMonth(r, year, month) {
    const dtStart = r.start_date || r.kickoff_date;
    if (!dtStart || !(r.mandays_assessment > 0)) return 0;

    const ko = new Date(dtStart);
    let curYear = ko.getFullYear();
    let curMonth = ko.getMonth();
    let remaining = r.mandays_assessment;

    const getWorkdays = getWorkdaysInMonth || (window.PortalShared && window.PortalShared.getWorkdaysInMonth);
    const getWorkingDays = workingDaysBetween || (window.PortalShared && window.PortalShared.workingDaysBetween);

    while (remaining > 0) {
      const days = getWorkdays(curYear, curMonth);
      let avail = 0;
      if (curYear === ko.getFullYear() && curMonth === ko.getMonth()) {
        const overlap = getWorkingDays(dtStart, new Date(curYear, curMonth + 1, 0).toLocaleDateString('en-CA')).days;
        avail = overlap;
      } else {
        avail = days.workdays;
      }

      const consumed = Math.min(remaining, avail);
      if (curYear === year && curMonth === month) {
        return consumed;
      }
      remaining -= consumed;
      curMonth++;
      if (curMonth > 11) { curMonth = 0; curYear++; }
      if (curYear > year + 2) break;
    }
    return 0;
  }

  window.AllocationShared = {
    buildAllocationMonths,
    assessmentMandaysInMonth
  };
})();
