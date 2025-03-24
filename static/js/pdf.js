document.getElementById('downloadPDF').addEventListener('click', function () {
    const chartSection = document.getElementById('carbonChart');
  
    html2canvas(chartSection).then((canvas) => {
      const link = document.createElement('a');
      link.href = canvas.toDataURL('image/png');
      link.download = 'Carbon_Footprint_Report.png';
      link.click();
    });
  });
  