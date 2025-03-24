document.addEventListener('DOMContentLoaded', function () {
    const ctx = document.getElementById('carbonChart').getContext('2d');
  
    // Example data, replace with backend data using Jinja2
    const data = {
      labels: ['Energy Footprint', 'Waste Footprint', 'Travel Footprint'],
      datasets: [{
        label: 'Carbon Emissions (kg CO2)',
        data: [energyFootprint, wasteFootprint, travelFootprint],
        backgroundColor: ['#007bff', '#ffc107', '#dc3545'],
      }]
    };
  
    const config = {
      type: 'bar',
      data: data,
      options: {
        responsive: true,
        scales: {
          y: { beginAtZero: true }
        }
      }
    };
  
    new Chart(ctx, config);
  });
  